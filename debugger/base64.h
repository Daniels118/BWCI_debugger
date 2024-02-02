#pragma once

bool base64_encode(const char* src, size_t len, char* out, size_t* out_len);
bool base64_decode(const unsigned char* src, size_t len, char* out, size_t* out_len);
