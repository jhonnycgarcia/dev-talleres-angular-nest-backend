import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtSrv: JwtService,
    private authSrv: AuthService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    const payload = await this.verifyToken(token);

    const user = await this.authSrv.findUserById(payload.id);
    if(!user) { throw new UnauthorizedException('User does not exist'); }
    if(!user.isActive) { throw new UnauthorizedException('User is not active'); }

    request['user'] = user;
    return true;
  }

  private async verifyToken(token: string): Promise<JwtPayload> {
    try {
      return this.jwtSrv.verify<JwtPayload>(token, {
        secret: process.env.JWT_SEED,
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
