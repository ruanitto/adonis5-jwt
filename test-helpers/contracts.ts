import { User } from '../example/models'

declare module '@ioc:Adonis/Addons/Auth' {
  interface ProvidersList {
    lucid: {
      implementation: LucidProviderContract<typeof User>
      config: LucidProviderConfig<typeof User>
    }
    database: {
      config: DatabaseProviderConfig
      implementation: DatabaseProviderContract<DatabaseProviderRow>
    }
  }

  interface GuardsList {
    jwt: {
      implementation: JWTGuardContract<'lucid', 'jwt'>
      config: JWTGuardConfig<'database'>
    }
  }
}

declare module '@ioc:Adonis/Core/Hash' {
  interface HashersList {
    bcrypt: HashDrivers['bcrypt']
  }
}
