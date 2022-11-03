#include <stdint.h>
#include <stdio.h>
#include "common.h"
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeBytesAsString(100);
    str2wcstring(str);
    return 0;
}