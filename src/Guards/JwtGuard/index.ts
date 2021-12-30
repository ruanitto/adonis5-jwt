import {
  JWTTokenContract,
  JWTGuardContract,
  JWTLoginOptions,
  JWTTokenGenerated,
  JWTGuardConfig,
  ProviderTokenContract,
  TokenProviderContract,
  UserProviderContract,
} from '@ioc:Adonis/Addons/Auth'
import { BaseGuard } from '@adonisjs/auth/build/src/Guards/Base'
import { DateTime } from 'luxon'
import { EmitterContract } from '@ioc:Adonis/Core/Event'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { string, base64 } from '@poppinss/utils/build/helpers'
import { createHash } from 'crypto'
import { ProviderToken } from '@adonisjs/auth/build/src/Tokens/ProviderToken'
import { AuthenticationException } from '@adonisjs/auth/build/standalone'
import { omit, isPlainObject } from 'lodash'
import { sign, verify } from 'jsonwebtoken'
import JwtAuthenticationException from '../../Exceptions/JwtAuthenticationException'
import { JWTToken } from '../../Tokens/JwtToken'

/**
 * Exposes the API to generate and authenticate HTTP request using jwt tokens
 */
export class JWTGuard extends BaseGuard<any> implements JWTGuardContract<any, any> {
  /**
   * Token fetched as part of the authenticate or the login
   * call
   */
  public token?: ProviderTokenContract

  /**
   * Reference to the parsed token
   */
  private parsedToken?: {
    value: string
    tokenId: string
    jwtToken: string
  }

  /**
   * Token type for the persistance store
   */
  private tokenType = this.config.tokenProvider.type || 'jwt_token'

  /**
   * Length of the raw token. The hash length will vary
   */
  private tokenLength = 60

  /**
   * constructor of class.
   */
  constructor(
    name: string,
    public config: JWTGuardConfig<any>,
    private emitter: EmitterContract,
    provider: UserProviderContract<any>,
    private ctx: HttpContextContract,
    public tokenProvider: TokenProviderContract
  ) {
    super(name, config, provider)
  }

  /**
   * Verify user credentials and perform login
   */
  public async attempt(uid: string, password: string, options?: JWTLoginOptions): Promise<any> {
    const user = await this.verifyCredentials(uid, password)
    return this.login(user, options)
  }

  /**
   * Same as [[authenticate]] but returns a boolean over raising exceptions
   */
  public async check(): Promise<boolean> {
    try {
      await this.authenticate()
    } catch (error) {
      /**
       * Throw error when it is not an instance of the authentication
       */
      if (!(error instanceof AuthenticationException)) {
        throw error
      }

      this.ctx.logger.trace(error, 'Authentication failure')
    }

    return this.isAuthenticated
  }

  /**
   * Authenticates the current HTTP request by checking for the bearer token
   */
  public async authenticate(): Promise<any> {
    /**
     * Return early when authentication has already attempted for
     * the current request
     */
    if (this.authenticationAttempted) {
      return this.user
    }

    this.authenticationAttempted = true

    /**
     * Ensure the "Authorization" header value exists
     */
    const token = this.getBearerToken()
    const { tokenId, value } = this.parsePublicToken(token)

    /**
     * Query token and user
     */
    const providerToken = await this.getProviderToken(tokenId, value)
    const providerUser = await this.getUserById(providerToken.userId)

    /**
     * Marking user as logged in
     */
    this.markUserAsLoggedIn(providerUser.user, true)
    this.token = providerToken

    /**
     * Emit authenticate event. It can be used to track user logins.
     */
    this.emitter.emit(
      'adonis:api:authenticate',
      this.getAuthenticateEventData(providerUser.user, this.token)
    )

    return providerUser.user
  }

  /**
   * Generate token for a user. It is merely an alias for `login`
   */
  public async generate(
    user: any,
    payload?: any,
    options?: JWTLoginOptions
  ): Promise<JWTTokenContract<any>> {
    options = Object.assign({}, options, { payload })
    return this.login(user, options)
  }

  /**
   * Login user using their id
   */
  public async loginViaId(id: string | number, options?: JWTLoginOptions): Promise<any> {
    const providerUser = await this.findById(id)
    return this.login(providerUser.user, options)
  }

  /**
   * Login a user
   */
  public async login(user: any, options?: JWTLoginOptions): Promise<any> {
    /**
     * Normalize options with defaults
     */
    let {
      expiresIn,
      name,
      payload: jwtPayload,
      withRefresh,
      expiresRefresh,
      ...meta
    } = Object.assign({ name: 'JWT Access Token' }, options)

    /**
     * Since the login method is not exposed to the end user, we cannot expect
     * them to instantiate and pass an instance of provider user, so we
     * create one manually.
     */
    const providerUser = await this.getUserForLogin(user, this.config.provider.identifierKey)

    /**
     * "getUserForLogin" raises exception when id is missing, so we can
     * safely assume it is defined
     */
    const id = providerUser.getId()!

    const token = this.generateTokenForPersistance(expiresIn ?? this.config.jwtOptions.expiresIn)

    /**
     * Persist token to the database. Make sure that we are always
     * passing the hash to the storage driver
     */
    const providerToken = new ProviderToken(name, token.hash, id, this.tokenType)
    providerToken.expiresAt = token.expiresAt
    providerToken.meta = meta
    const tokenId = await this.tokenProvider.write(providerToken)

    /**
     * The jwt payload
     *
     * @type {Object}
     */
    const payload: any = { uid: id, sub: id }

    if (jwtPayload === true) {
      /**
       * Attach user as data object only when
       * jwtPayload is true
       */
      const data = typeof user.toJSON === 'function' ? user.toJSON() : user

      /**
       * Remove password from jwt data
       */
      payload.data = omit(data, 'password')
    } else if (isPlainObject(jwtPayload)) {
      /**
       * Attach payload as it is when it's an object
       */
      payload.data = jwtPayload
    }

    const jwtToken = this.generateJWTToken(
      `${base64.urlEncode(tokenId)}.${token.token}`,
      options,
      payload
    )

    if (withRefresh) {
      const refreshToken = this.generateTokenForPersistance(expiresRefresh)

      /**
       * Persist refreshToken to the database. Make sure that we are always
       * passing the hash to the storage driver
       */
      const providerRefreshToken = new ProviderToken(name, refreshToken.hash, id, this.tokenType)
      providerRefreshToken.meta = meta
      const refreshTokenId = await this.tokenProvider.write(providerRefreshToken)

      jwtToken.refreshToken = `${base64.urlEncode(refreshTokenId)}.${refreshToken.token}`
    }

    /**
     * Construct a new API Token instance
     */
    const apiToken = new JWTToken(
      name,
      jwtToken.accessToken,
      jwtToken.refreshToken,
      providerUser.user
    )
    apiToken.tokenHash = token.hash
    apiToken.expiresAt = token.expiresAt
    apiToken.meta = meta || {}

    /**
     * Marking user as logged in
     */
    this.markUserAsLoggedIn(providerUser.user)
    this.token = providerToken

    /**
     * Emit login event. It can be used to track user logins.
     */
    this.emitter.emit('adonis:api:login', this.getLoginEventData(providerUser.user, apiToken))

    return apiToken
  }

  /**
   * Logout by removing the token from the storage
   */
  public async logout(_options?: JWTLoginOptions): Promise<void> {
    if (!this.authenticationAttempted) {
      await this.check()
    }

    /**
     * Clean up token from storage
     */
    if (this.parsedToken) {
      await this.tokenProvider.destroy(this.parsedToken.tokenId, this.tokenType)
    }

    this.markUserAsLoggedOut()
  }

  /**
   * Alias for the logout method
   */
  public revoke(): Promise<void> {
    return this.logout()
  }

  /**
   * Serialize toJSON for JSON.stringify
   */
  public toJSON(): any {
    return {
      isLoggedIn: this.isLoggedIn,
      isGuest: this.isGuest,
      authenticationAttempted: this.authenticationAttempted,
      isAuthenticated: this.isAuthenticated,
      user: this.user,
    }
  }

  /**
   * Generates a new token + hash for the persistance
   */
  private generateTokenForPersistance(expiresIn?: string | number) {
    const token = string.generateRandom(this.tokenLength)

    return {
      token,
      hash: this.generateHash(token),
      expiresAt: this.getExpiresAtDate(expiresIn),
    }
  }

  /**
   * Generate JWTToken
   */
  private generateJWTToken(tokenId: string, options?: JWTLoginOptions, payload: any = {}) {
    const jwtOptions = omit(this.config.jwtOptions, ['secret', 'public'])

    let { expiresIn } = Object.assign({}, options)

    if (expiresIn) {
      jwtOptions.expiresIn = expiresIn
    }

    jwtOptions.jwtid = tokenId
    jwtOptions.header = { jti: tokenId }

    const accessToken = sign(payload, this.config.jwtOptions.secret as string, jwtOptions)

    // const refreshToken = withRefresh ? this.generateTokenForPersistance(expiresIn) : null
    const refreshToken: string | null = null

    return {
      accessToken,
      refreshToken,
      expiresAt: this.getExpiresAtDate(expiresIn),
    } as JWTTokenGenerated
  }

  /**
   * Converts value to a sha256 hash
   */
  private generateHash(token: string) {
    return createHash('sha256').update(token).digest('hex')
  }

  /**
   * Converts expiry duration to an absolute date/time value
   */
  private getExpiresAtDate(expiresIn?: string | number) {
    if (!expiresIn) {
      return
    }

    const milliseconds = typeof expiresIn === 'string' ? string.toMs(expiresIn) : expiresIn
    return DateTime.local().plus({ milliseconds })
  }

  /**
   * Returns the bearer token
   */
  private getBearerToken(): string {
    /**
     * Ensure the "Authorization" header value exists
     */
    const token = this.ctx.request.header('Authorization')
    if (!token) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure that token has minimum of two parts and the first
     * part is a constant string named `bearer`
     */
    const [type, value] = token.split(' ')
    if (!type || type.toLowerCase() !== 'bearer' || !value) {
      throw AuthenticationException.invalidToken(this.name)
    }

    return value
  }

  /**
   * Parses the token received in the request. The method also performs
   * some initial level of sanity checks.
   */
  private parsePublicToken(token: string) {
    const parts = token.split('.')

    /**
     * Ensure the token has two parts
     */
    if (parts.length !== 3) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure the first part is a base64 encode id
     */
    const tokenHeader = base64.urlDecode(parts.splice(0, 1)[0], undefined, true)

    if (!tokenHeader) {
      throw AuthenticationException.invalidToken(this.name)
    }

    const jti = JSON.parse(tokenHeader).jti
    if (!jti) {
      throw AuthenticationException.invalidToken(this.name)
    }

    const jtiParts = jti.split('.')

    /**
     * Ensure the token has two parts
     */
    if (jtiParts.length !== 2) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure the first part is a base64 encode id
     */
    const tokenId = base64.urlDecode(jtiParts[0], undefined, true)
    if (!tokenId) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure 2nd part of the token has the expected length
     */
    if (jtiParts[1].length !== this.tokenLength) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure 2nd part of the token has the expected length
     */
    const value = jtiParts[1]

    /**
     * Set parsed token
     */
    this.parsedToken = { tokenId, value, jwtToken: token }

    return this.parsedToken
  }

  /**
   * Returns the token by reading it from the token provider
   */
  private async getProviderToken(tokenId: string, value: string): Promise<ProviderTokenContract> {
    const providerToken = await this.tokenProvider.read(
      tokenId,
      this.generateHash(value),
      this.tokenType
    )

    if (!providerToken) {
      throw AuthenticationException.invalidToken(this.name)
    }

    return providerToken
  }

  /**
   * Returns user from the user session id
   */
  private async getUserById(id: string | number) {
    const token = this.parsedToken?.jwtToken || ''

    const options = omit(this.config.jwtOptions, ['secret', 'public', 'uid'])
    const secretOrPublicKey =
      this.config.jwtOptions.public !== null
        ? this.config.jwtOptions.public
        : this.config.jwtOptions.secret
    // return verifyToken(token, secretOrPublicKey, options)

    // const secret = this.generateKey(this.config.jwtOptions.secret as string)
    try {
      const payload = await verify(token, secretOrPublicKey as string, options)

      const { exp, uid, sub }: any = payload

      if (exp && exp < Math.floor(DateTime.now().toSeconds())) {
        throw AuthenticationException.invalidToken(this.name)
      }

      if (!uid && !sub) {
        throw AuthenticationException.invalidToken(this.name)
      }

      if (uid !== id) {
        throw AuthenticationException.invalidToken(this.name)
      }

      const authenticatable = await this.provider.findById(id)

      if (!authenticatable.user) {
        throw AuthenticationException.invalidToken(this.name)
      }

      return authenticatable
    } catch ({ name, message }) {
      if (name === 'TokenExpiredError') {
        throw JwtAuthenticationException.expiredJwtToken(this.name)
      }
      throw JwtAuthenticationException.invalidJwtToken(this.name)
    }
  }

  /**
   * Returns data packet for the login event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - API token
   */
  private getLoginEventData(user: any, token: JWTTokenContract<any>): any {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      token,
    }
  }

  /**
   * Returns data packet for the authenticate event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - A boolean to tell if logged in viaRemember or not
   */
  private getAuthenticateEventData(user: any, token: ProviderTokenContract): any {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      token,
    }
  }
}
