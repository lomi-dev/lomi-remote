#include <stdint.h>
#include <stddef.h>
// Result: status byte (0 ok, 1 error) then data; release with lomi_core_bytes_free(ptr, *out_len).
// NULL on an invalid `op` or an internal panic. `handle` 0 for stateless and creating operations.
uint8_t *lomi_core_call(uint32_t handle, const char *op, const uint8_t *args, size_t args_len,
                        const uint8_t *payload, size_t payload_len, size_t *out_len);
void lomi_core_bytes_free(uint8_t *ptr, size_t len);
void lomi_core_free(uint32_t handle);
