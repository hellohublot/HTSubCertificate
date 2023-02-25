## HTSubCertificate
A library for creating subordinate certificates on iOS using OpenSSL

## Features

- Provide the public key and private key of the root certificate, and create a P12 certificate based on the password

## Install
```ruby
pod 'HTOpenSSL', :git => 'https://github.com/hellohublot/HTOpenSSL.git'
```

## Usage


```swift
/*
	hostchar: Domain name to create sub-certificate
	cacrtstruct: The structure of the root certificate public key crt
	cakeystruct: The structure of the root certificate private key key
	passwordchar: Created sub-certificate pk12 password
*/

createPK12With(&hostchar, cacrtstruct, cakeystruct, &passwordchar)

```

## Contact

hellohublot, hublot@aliyun.com
