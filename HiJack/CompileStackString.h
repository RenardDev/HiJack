#pragma once

#ifndef _COMPILESTACKSTRING_H_
#define _COMPILESTACKSTRING_H_

// STL
#include <type_traits>
#include <array>

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#if defined(_MSC_VER)
#define _STACKSTRING_NO_INLINE __declspec(noinline)
#define _STACKSTRING_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define _STACKSTRING_NO_INLINE __attribute__((noinline))
#define _STACKSTRING_FORCE_INLINE __attribute__((always_inline))
#else
#define _STACKSTRING_NO_INLINE
#define _STACKSTRING_FORCE_INLINE inline
#endif

// ----------------------------------------------------------------
// StackString
// ----------------------------------------------------------------

namespace StackString {

	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	template<typename T, std::size_t N>
	struct ByteIO;

	template<typename T>
	struct ByteIO<T, 1> {
		constexpr static std::array<unsigned char, 1> to(T Value) noexcept {
			std::array<unsigned char, 1> out {{ static_cast<unsigned char>(Value) }};
			return out;
		}

		constexpr static T from(const std::array<unsigned char, 1>& bytes) noexcept {
			return static_cast<T>(bytes[0]);
		}
	};

	template<typename T>
	struct ByteIO<T, 2> {
		constexpr static std::array<unsigned char, 2> to(T Value) noexcept {
			const unsigned short unX = static_cast<unsigned short>(Value);

			std::array<unsigned char, 2> out {{
				static_cast<unsigned char>( unX       & 0xFF),
				static_cast<unsigned char>((unX >> 8) & 0xFF)
			}};

			return out;
		}

		constexpr static T from(const std::array<unsigned char, 2>& bytes) noexcept {
			const unsigned short unX = static_cast<unsigned short>(bytes[0]) |
									  (static_cast<unsigned short>(bytes[1]) << 8);
			return static_cast<T>(unX);
		}
	};

	template<typename T>
	struct ByteIO<T, 4> {
		constexpr static std::array<unsigned char, 4> to(T Value) noexcept {
			const unsigned int unX = static_cast<unsigned int>(Value);

			std::array<unsigned char, 4> out {{
				static_cast<unsigned char>( unX        & 0xFF),
				static_cast<unsigned char>((unX >>  8) & 0xFF),
				static_cast<unsigned char>((unX >> 16) & 0xFF),
				static_cast<unsigned char>((unX >> 24) & 0xFF)
			}};

			return out;
		}

		constexpr static T from(const std::array<unsigned char, 4>& bytes) noexcept {
			const unsigned int unX = static_cast<unsigned int>(bytes[0])        |
									(static_cast<unsigned int>(bytes[1]) <<  8) |
									(static_cast<unsigned int>(bytes[2]) << 16) |
									(static_cast<unsigned int>(bytes[3]) << 24);
			return static_cast<T>(unX);
		}
	};

	template <typename T>
	constexpr std::array<unsigned char, sizeof(T)> ToBytes(T Value) noexcept {
		static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4, "Unsupported character size");
		return ByteIO<T, sizeof(T)>::to(Value);
	}

	template <typename T>
	constexpr T FromBytes(const std::array<unsigned char, sizeof(T)>& bytes) noexcept {
		static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4, "Unsupported character size");
		return ByteIO<T, sizeof(T)>::from(bytes);
	}

	template <unsigned long long unLength, typename T, unsigned long long unLine = 0, unsigned long long unCounter = 0>
	class StackString {
	private:
		static constexpr std::size_t kLength = static_cast<std::size_t>(unLength);
		static constexpr std::size_t kPlainBytes = kLength * sizeof(T);

	public:
		class DecryptedString {
		public:
			_STACKSTRING_FORCE_INLINE explicit DecryptedString(const StackString& EncryptedString) noexcept {
				for (std::size_t i = 0; i < kLength; ++i) {
					std::array<unsigned char, sizeof(T)> tmp {};
					for (std::size_t k = 0; k < sizeof(T); ++k) {
						const std::size_t j = i * sizeof(T) + k;
						tmp[k] = EncryptedString.m_pStorage[j] ^ 0xFF;
					}

					m_pBuffer[i] = FromBytes<T>(tmp);
				}
			}

			_STACKSTRING_FORCE_INLINE ~DecryptedString() noexcept {
				Clear();
			}

			DecryptedString(const DecryptedString&) = delete;
			DecryptedString& operator=(const DecryptedString&) = delete;

			_STACKSTRING_FORCE_INLINE DecryptedString(DecryptedString&& other) noexcept {
				for (std::size_t i = 0; i < kLength; ++i) {
					m_pBuffer[i] = other.m_pBuffer[i];
				}

				other.Clear();
			}

			_STACKSTRING_FORCE_INLINE DecryptedString& operator=(DecryptedString&& other) noexcept {
				if (this != &other) {
					for (std::size_t i = 0; i < kLength; ++i) {
						m_pBuffer[i] = other.m_pBuffer[i];
					}

					other.Clear();
				}

				return *this;
			}

			_STACKSTRING_FORCE_INLINE T* get() noexcept { return m_pBuffer; }
			_STACKSTRING_FORCE_INLINE operator T* () noexcept { return get(); }
			_STACKSTRING_FORCE_INLINE const T* c_str() const noexcept { return m_pBuffer; }
			_STACKSTRING_FORCE_INLINE operator const T* () const noexcept { return c_str(); }

		private:
			_STACKSTRING_FORCE_INLINE void Clear() noexcept {
				volatile T* pData = m_pBuffer;
				for (std::size_t i = 0; i < kLength; ++i) {
					pData[i] = T {};
				}
			}

			T m_pBuffer[kLength] {};
		};

		_STACKSTRING_FORCE_INLINE constexpr StackString(T* pData) noexcept {
			for (std::size_t i = 0; i < kLength; ++i) {
				const auto bytes = ToBytes<T>(pData[i]);
				for (std::size_t k = 0; k < sizeof(T); ++k) {
					const std::size_t j = i * sizeof(T) + k;
					m_pStorage[j] = static_cast<unsigned char>(bytes[k] ^ 0xFF);
				}
			}
		}

		_STACKSTRING_FORCE_INLINE DecryptedString Decrypt() const noexcept {
			return DecryptedString(*this);
		}

	private:
		unsigned char m_pStorage[kPlainBytes] {};
	};
}

#define _STACKSTRING(S)                                                                                                                                                                         \
	([]() -> auto {                                                                                                                                                                             \
		constexpr size_t unLength = std::extent_v<std::remove_reference_t<decltype(S)>>;                                                                                                        \
		constexpr auto Encrypted = StackString::StackString<unLength, StackString::clean_type<decltype(S[0])>, __LINE__, __COUNTER__>(const_cast<StackString::clean_type<decltype(S[0])>*>(S)); \
		return Encrypted.Decrypt();                                                                                                                                                             \
	} ())

#define STACKSTRING(S) _STACKSTRING(S)

#undef _STACKSTRING_FORCE_INLINE
#undef _STACKSTRING_NO_INLINE

#endif // !_COMPILESTACKSTRING_H_
