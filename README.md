## Features

- Support to create sub-certificate, pass in CA root certificate, create sub-certificate based on domain name p12

## Usage

```ruby
pod 'HTOpenSSL', :git => 'https://github.com/hellohublot/HTOpenSSL.git'
```
```swift
/*
	hostchar: Domain name to create sub-certificate
	cacrtstruct: The structure of the root certificate public key crt
	cakeystruct: The structure of the root certificate private key key
	passwordchar: Created sub-certificate pk12 password
*/

createPK12With(&hostchar, cacrtstruct, cakeystruct, &passwordchar)

```

## Author

hellohublot, hublot@aliyun.com
