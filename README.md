# ca-adoption-scanner

This is a basic Golang tool for attempting to observe the HTTPS adoption rate of SSL certificates
issued by a specific issuer using entries in a Certificate Transparency log as it's initial data
source.

Using a filtered list of X509 certificates the scanner will attempt to connect to each DNS name
specified in a certificate and collect various information about whether the name is available,
serves HTTPS, and serves the expected leaf certificate.

By default the `certly.io` log is used since it is a. the smallest on disk, and b. it contains
all of the certificates issued by Let's Encrypt, the CA this tool was created to track (the
default issuer common name filter also reflects this). 

## TODO

* Add checking for OCSP status in `checkName`
  * Add check if stapled matches queried
* Add cipher suite strength conversion (I forget how chromium does this...)
* Add method to randomly sample from filtered chan (or via `entries.Map` again maybe?)
* Add method to record stats to disk
* Cleanup many... things
