- 支持代码创建子证书，传入 CA 根证书，根据域名创建子证书 p12

## Usage

```ruby
pod 'HTOpenSSL', :git => 'https://github.com/hellohublot/HTOpenSSL.git'
```
```swift
/*
	hostchar: 要创建子证书的域名
	cacrtstruct: 根证书公钥 crt 的结构体
	cakeystruct: 根证书私钥 key 的结构体
	passwordchar: 创建的子证书 pk12 密码
*/

createPK12With(&hostchar, cacrtstruct, cakeystruct, &passwordchar)

```

## Author

hellohublot, hublot@aliyun.com
