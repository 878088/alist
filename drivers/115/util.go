package _115

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alist-org/alist/v3/internal/conf"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/pkg/http_range"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"

	driver115 "github.com/SheltonZhu/115driver/pkg/driver"
	crypto "github.com/gaoyb7/115drive-webdav/115"
	"github.com/orzogc/fake115uploader/cipher"
	"github.com/pkg/errors"
)

var UserAgent = driver115.UA115Browser

func (d *Pan115) login() error {
	var err error
	opts := []driver115.Option{
		driver115.UA(UserAgent),
		func(c *driver115.Pan115Client) {
			c.Client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: conf.Conf.TlsInsecureSkipVerify})
		},
	}
	d.client = driver115.New(opts...)
	cr := &driver115.Credential{}
	if d.QRCodeToken != "" {
		s := &driver115.QRCodeSession{
			UID: d.QRCodeToken,
		}
		if cr, err = d.client.QRCodeLoginWithApp(s, driver115.LoginApp(d.QRCodeSource)); err != nil {
			return errors.Wrap(err, "failed to login by qrcode")
		}
		d.Cookie = fmt.Sprintf("UID=%s;CID=%s;SEID=%s", cr.UID, cr.CID, cr.SEID)
		d.QRCodeToken = ""
	} else if d.Cookie != "" {
		if err = cr.FromCookie(d.Cookie); err != nil {
			return errors.Wrap(err, "failed to login by cookies")
		}
		d.client.ImportCredential(cr)
	} else {
		return errors.New("missing cookie or qrcode account")
	}
	return d.client.LoginCheck()
}

func (d *Pan115) getFiles(fileId string) ([]FileObj, error) {
	res := make([]FileObj, 0)
	if d.PageSize <= 0 {
		d.PageSize = driver115.FileListLimit
	}
	files, err := d.client.ListWithLimit(fileId, d.PageSize)
	if err != nil {
		return nil, err
	}
	for _, file := range *files {
		res = append(res, FileObj{file})
	}
	return res, nil
}

const (
	appVer = "27.0.3.7"
)

func (c *Pan115) getAppVer() string {
	// todo add some cache？
	vers, err := c.client.GetAppVersion()
	if err != nil {
		return appVer
	}
	for _, ver := range vers {
		if ver.AppName == "win" {
			return ver.Version
		}
	}
	return appVer
}

func (c *Pan115) DownloadWithUA(pickCode, ua string) (*driver115.DownloadInfo, error) {
	key := crypto.GenerateKey()
	result := driver115.DownloadResp{}
	params, err := utils.Json.Marshal(map[string]string{"pickcode": pickCode})
	if err != nil {
		return nil, err
	}

	data := crypto.Encode(params, key)

	bodyReader := strings.NewReader(url.Values{"data": []string{data}}.Encode())
	reqUrl := fmt.Sprintf("%s?t=%s", driver115.ApiDownloadGetUrl, driver115.Now().String())
	req, _ := http.NewRequest(http.MethodPost, reqUrl, bodyReader)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", c.Cookie)
	req.Header.Set("User-Agent", ua)

	resp, err := c.client.Client.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := utils.Json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if err = result.Err(string(body)); err != nil {
		return nil, err
	}

	bytes, err := crypto.Decode(string(result.EncodedData), key)
	if err != nil {
		return nil, err
	}

	downloadInfo := driver115.DownloadData{}
	if err := utils.Json.Unmarshal(bytes, &downloadInfo); err != nil {
		return nil, err
	}

	for _, info := range downloadInfo {
		if info.FileSize < 0 {
			return nil, driver115.ErrDownloadEmpty
		}
		info.Header = resp.Request.Header
		return info, nil
	}
	return nil, driver115.ErrUnexpected
}

func (d *Pan115) rapidUpload(fileSize int64, fileName, dirID, preID, fileID string, stream model.FileStreamer) (*driver115.UploadInitResp, error) {
	var (
		ecdhCipher   *cipher.EcdhCipher
		encrypted    []byte
		decrypted    []byte
		encodedToken string
		err          error
		target       = "U_1_" + dirID
		bodyBytes    []byte
		result       = driver115.UploadInitResp{}
		fileSizeStr  = strconv.FormatInt(fileSize, 10)
	)
	if ecdhCipher, err = cipher.NewEcdhCipher(); err != nil {
		return nil, err
	}

	userID := strconv.FormatInt(d.client.UserID, 10)
	form := url.Values{}
	form.Set("appid", "0")
	form.Set("appversion", d.getAppVer())
	form.Set("userid", userID)
	form.Set("filename", fileName)
	form.Set("filesize", fileSizeStr)
	form.Set("fileid", fileID)
	form.Set("target", target)
	form.Set("sig", d.client.GenerateSignature(fileID, target))

	signKey, signVal := "", ""
	for retry := true; retry; {
		t := driver115.NowMilli()

		if encodedToken, err = ecdhCipher.EncodeToken(t.ToInt64()); err != nil {
			return nil, err
		}

		params := map[string]string{
			"k_ec": encodedToken,
		}

		form.Set("t", t.String())
		form.Set("token", d.client.GenerateToken(fileID, preID, t.String(), fileSizeStr, signKey, signVal))
		if signKey != "" && signVal != "" {
			form.Set("sign_key", signKey)
			form.Set("sign_val", signVal)
		}
		if encrypted, err = ecdhCipher.Encrypt([]byte(form.Encode())); err !=
