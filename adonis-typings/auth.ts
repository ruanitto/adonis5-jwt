import { DateTime } from 'luxon'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'

declare module '@ioc:Adonis/Addons/Auth' {
  /**
   * Login options
   */
  export type JWTLoginOptions = {
    name?: string
    expiresIn?: number | string
  } & { [key: string]: any }

  export type JWTTokenGenerated = {
    accessToken: string
    refreshToken: string | null
    expiresAt: DateTime | undefined
  }

  /**
   * Shape of data emitted by the login event
   */
  export type JWTLoginEventData<Provider extends keyof ProvidersList> = {
    name: string
    user: GetProviderRealUser<Provider>
    ctx: HttpContextContract
    token: JWTTokenContract<GetProviderRealUser<Provider>>
  }

  /**
   * JWT token is generated during the login call by the JWTGuard.
   */
  export interface JWTTokenContract<User extends any> {
    /**
     * Always a bearer token
     */
    type: 'bearer'

    /**
     * The user for which the token was generated
     */
    user: User

    /**
     * Date/time when the token will be expired
     */
    expiresAt?: DateTime

    /**
     * Time in seconds until the token is valid
     */
    expiresIn?: number

    /**
     * Any meta-data attached with the token
     */
    meta: any

    /**
     * Token name
     */
    name: string

    /**
     * Token public value
     */
    accessToken: string

    /**
     * Token public value
     */
    refreshToken: string | null

    /**
     * Token hash (persisted to the db as well)
     */
    tokenHash: string

    /**
     * Serialize token
     */
    toJSON(): {
      type: 'bearer'
      accessToken: string
      refreshToken: string | null
      expires_at?: string
      expires_in?: number
    }
  }

  /**
   * Shape of the JWT guard
   */
  export interface JWTGuardContract<
    Provider extends keyof ProvidersList,
    Name extends keyof GuardsList
  > extends GuardContract<Provider, Name> {
    token?: ProviderTokenContract
    tokenProvider: TokenProviderContract

    /**
     * Attempt to verify user credentials and perform login
     */
    attempt(
      uid: string,
      password: string,
      options?: JWTLoginOptions
    ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>

    /**
     * Login a user without any verification
     */
    login(
      user: GetProviderRealUser<Provider>,
      options?: JWTLoginOptions
    ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>

    /**
     * Generate token for a user without any verification
     */
    generate(
      user: GetProviderRealUser<Provider>,
      payload?: any,
      options?: JWTLoginOptions
    ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>

    /**
     * Alias for logout
     */
    revoke(): Promise<void>

    /**
     * Login a user using their id
     */
    loginViaId(
      id: string | number,
      options?: JWTLoginOptions
    ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>
  }

  /**
   * Shape of JWT guard config.
   */
  export type JWTGuardConfig<Provider extends keyof ProvidersList> = {
    /**
     * Driver name is always constant
     */
    driver: 'jwt'

    /**
     * Provider for managing tokens
     */
    tokenProvider: DatabaseTokenProviderConfig | RedisTokenProviderConfig

    /**
     * User provider
     */
    provider: ProvidersList[Provider]['config']

    jwtOptions: {
      secret?: string | Buffer
      public?: string | Buffer

      /**
       * Signature algorithm. Could be one of these values :
       * - HS256:    HMAC using SHA-256 hash algorithm (default)
       * - HS384:    HMAC using SHA-384 hash algorithm
       * - HS512:    HMAC using SHA-512 hash algorithm
       * - RS256:    RSASSA using SHA-256 hash algorithm
       * - RS384:    RSASSA using SHA-384 hash algorithm
       * - RS512:    RSASSA using SHA-512 hash algorithm
       * - ES256:    ECDSA using P-256 curve and SHA-256 hash algorithm
       * - ES384:    ECDSA using P-384 curve and SHA-384 hash algorithm
       * - ES512:    ECDSA using P-521 curve and SHA-512 hash algorithm
       * - none:     No digital signature or MAC value included
       */
      algorithm:
        | 'HS256'
        | 'HS384'
        | 'HS512'
        | 'RS256'
        | 'RS384'
        | 'RS512'
        | 'ES256'
        | 'ES384'
        | 'ES512'
        | 'PS256'
        | 'PS384'
        | 'PS512'
        | 'none'
      keyid?: string
      /** expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms.js).  Eg: 60, '2 days', '10h', '7d' */
      expiresIn?: string | number
      /** expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms.js).  Eg: 60, '2 days', '10h', '7d' */
      notBefore?: string | number
      audience?: string | string[]
      subject?: string
      issuer?: string
      jwtid?: string
      mutatePayload?: boolean
      noTimestamp?: boolean
      header?: object
      encoding?: string
    }
  }

  /**
   * List of providers mappings used by the app. Using declaration
   * merging, one must extend this interface.
   *
   * MUST BE SET IN THE USER LAND.
   *
   * Example:
   *
   * lucid: {
   *   config: LucidProviderConfig<any>,
   *   implementation: LucidProviderContract<any>,
   * }
   *
   */
  export interface ProvidersList {}
}
