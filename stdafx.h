// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>



// TODO: reference additional headers your program requires here
#include <fstream>
#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <time.h>  
#include <sstream>
#include "osrng.h"
#include "cryptlib.h"
#include "filters.h"
#include "des.h"
#include "modes.h"
#include "secblock.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "hex.h"
#include "cbcmac.h"
#include "sha.h"
#include "hmac.h"
#include <iostream>
#include <string>
#include <stdexcept>
#include <queue.h>
#include <files.h>
#include "rsa.h"
#include <cryptlib.h>
#include "hex.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::exit;
using std::cin;
using CryptoPP::SHA256;
using CryptoPP::HMAC;
using CryptoPP::Exception;
using CryptoPP::HexEncoder;
using CryptoPP::CBC_Mode;
using CryptoPP::SecByteBlock;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::DES_EDE2;
using CryptoPP::AutoSeededRandomPool;
using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::runtime_error;
using CryptoPP::ByteQueue;
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::RSA;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSource;
