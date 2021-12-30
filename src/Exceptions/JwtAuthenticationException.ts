import { AuthenticationException } from '@adonisjs/auth/build/src/Exceptions/AuthenticationException'

/*
|--------------------------------------------------------------------------
| Exception
|--------------------------------------------------------------------------
|
| The Exception class imported from `@adonisjs/core` allows defining
| a status code and error code for every exception.
|
| @example
| new JwtGuardException('message', 500, 'E_RUNTIME_EXCEPTION')
|
*/
export default class JwtAuthenticationException extends AuthenticationException {
  /**
   * Missing/Invalid token or unable to lookup user from the token
   */
  public static expiredJwtToken(guard: string) {
    return new this(
      'The jwt token has been expired. Generate a new one to continue',
      'E_JWT_TOKEN_EXPIRED',
      guard
    )
  }

  public static invalidJwtToken(guard: string) {
    return new this('The Jwt token is invalid', 'E_INVALID_JWT_TOKEN', guard)
  }

  public static invalidRefreshToken(refreshToken: string) {
    return new this(`Invalid refresh token ${refreshToken}`, 'E_INVALID_JWT_REFRESH_TOKEN')
  }

  public static invalidApiToken(guard: string) {
    return new this('The api token is missing or invalid', 'E_INVALID_API_TOKEN', guard)
  }
}
