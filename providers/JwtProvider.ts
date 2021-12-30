import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { JWTGuard } from '../src/Guards/JwtGuard'

/*
|--------------------------------------------------------------------------
| Provider
|--------------------------------------------------------------------------
|
| Your application is not ready when this file is loaded by the framework.
| Hence, the top level imports relying on the IoC container will not work.
| You must import them inside the life-cycle methods defined inside
| the provider class.
|
| @example:
|
| public async ready () {
|   const Database = (await import('@ioc:Adonis/Lucid/Database')).default
|   const Event = (await import('@ioc:Adonis/Core/Event')).default
|   Event.on('db:query', Database.prettyPrint)
| }
|
*/
export default class JwtV4GuardProvider {
  public static needsApplication = true
  constructor(protected app: ApplicationContract) {}

  public async register() {
    // All bindings are ready, feel free to use them
    const Auth = this.app.container.use('Adonis/Addons/Auth')

    Auth.extend('guard', 'jwt', (_auth: any, _mapping, _config, _provider, _ctx) => {
      const tokenProvider = _auth.makeTokenProviderInstance(_config.tokenProvider)
      return new JWTGuard(
        _mapping,
        _config,
        _auth.getEmitter(),
        _provider,
        _ctx,
        tokenProvider
      ) as any
    })
  }
}
