#ifndef _TEST_INCLUDES_HPP_
#define _TEST_INCLUDES_HPP_


extern "C"
{
    #include "includes.h"
    #include "Commands.h"
    #include "CredentialStore.h"
    #include "Crypto.h"
    #include "Internal.h"
    #include "Session.h"
    #include "Validation.h"
};

#include "CppUnitTest.h"
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <iterator>


#endif  // _TEST_INCLUDES_HPP_
