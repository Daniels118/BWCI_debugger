#pragma once

bool base64_encode(const char* src, const size_t len, char* out, size_t* out_len);
bool base64_decode(const char* src, const size_t len, char* out, size_t* out_len);
