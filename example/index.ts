import { AuthConfig, AuthContract } from '@ioc:Adonis/Addons/Auth'

export const config: AuthConfig = {
  guard: 'jwt',
  guards: {
    jwt: {
      driver: 'jwt',
      jwtOptions: {
        algorithm: 'RS256',
      },
      provider: {
        driver: 'database',
        identifierKey: 'id',
        uids: ['email'],
        usersTable: 'User',
        connection: 'mysql',
      },
      tokenProvider: {
        driver: 'database',
        table: 'tokens',
      },
    },
  },
}

const a = {} as AuthContract
a.loginViaId(1)
// a.use('basic').
