import { DateTime } from 'luxon'
import { JWTTokenContract } from '@ioc:Adonis/Addons/Auth'

/**
 * JWT token represents a persisted token generated for a given user.
 *
 * Calling `token.toJSON()` will give you an object, that you can send back
 * as response to share the token with the client.
 */
export class JWTToken implements JWTTokenContract<any> {
  /**
   * The type of the token. Always set to bearer
   */
  public type = 'bearer' as const

  /**
   * The datetime in which the token will expire
   */
  public expiresAt?: DateTime

  /**
   * Time left until token gets expired
   */
  public expiresIn?: number

  /**
   * Any meta data attached to the token
   */
  public meta: any

  /**
   * Hash of the token saved inside the database. Make sure to never share
   * this with the client
   */
  public tokenHash: string

  constructor(
    public name: string, // Name associated with the token
    public accessToken: string, // The raw token value. Only available for the first time
    public refreshToken: string | null, // The raw refresh token value. Only available for the first time
    public user: any // The user for which the token is generated
  ) {}

  /**
   * Shareable version of the token
   */
  public toJSON() {
    return {
      type: this.type,
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
      ...(this.expiresAt ? { expires_at: this.expiresAt.toISO() || undefined } : {}),
      ...(this.expiresIn ? { expires_in: this.expiresIn } : {}),
    }
  }
}
