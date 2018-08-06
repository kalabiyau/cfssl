package pkcs11

import (
	"io/ioutil"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/letsencrypt/pkcs11key"
)

func New(caCertFile string, policy *config.Signing, cfg *Config) (signer.Signer, error) {
	if cfg == nil {
		return nil, errors.New(errors.PrivateKeyError, errors.ReadFailed)
	}

	log.Debugf("Loading PKCS #11 module %s", cfg.Module)
	certData, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, errors.New(errors.PrivateKeyError, errors.ReadFailed)
	}

	cert, err := helpers.ParseCertificatePEM(certData)
	if err != nil {
		return nil, err
	}
	publicKey, _ := ioutil.ReadFile("/Users/kalabiyau/Desktop/yubikey_ssl_ca/yubico-internal-https-subca-Artem-crt.pem")
	priv, err := pkcs11key.New(cfg.Module, cfg.Token, cfg.PIN, publicKey)
	log.Debugf("-> %s", cfg)
	log.Debugf("-> %s", cert)
	if err != nil {
		log.Debugf("-> %s", "Broken Priv Key")
		return nil, errors.New(errors.PrivateKeyError, errors.ReadFailed)
	}
	sigAlgo := signer.DefaultSigAlgo(priv)

	return local.NewSigner(priv, cert, sigAlgo, policy)
}
