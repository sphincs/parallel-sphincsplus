#if !defined( TEST_SPHINCS_H_ )
#define TEST_SPHINCS_H_
enum noise_level { quiet, whisper, loud };
	
extern bool test_testvector(bool fast_flag, enum noise_level level);
extern bool test_sha512(bool fast_flag, enum noise_level level);
extern bool test_keygen(bool fast_flag, enum noise_level level);
extern bool test_sign(bool fast_flag, enum noise_level level);
extern bool test_verify(bool fast_flag, enum noise_level level);
extern bool test_thread(bool fast_flag, enum noise_level level);
extern bool test_fault(bool fast_flag, enum noise_level level);

#endif /* TEST_SPHINCS_H_ */
