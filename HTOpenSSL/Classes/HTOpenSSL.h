//
//  HTOpenSSL.h
//  Pods
//
//  Created by hublot on 2018/2/8.
//

#ifndef HTOpenSSL_h
#define HTOpenSSL_h


#endif /* HTOpenSSL_h */

typedef struct {
	const void *address;
	const int length;
} __attribute__((packed)) data_st;

data_st createPK12With(char *host, data_st cacrtdata, data_st cakeydata, char *password);
