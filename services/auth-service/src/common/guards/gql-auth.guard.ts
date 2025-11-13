import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { AuthService } from '../../auth/auth.service';

@Injectable()
export class GqlAuthGuard implements CanActivate {
    constructor(private readonly authService: AuthService) { }

    canActivate(context: ExecutionContext): boolean {
        const ctx = GqlExecutionContext.create(context);
        const req = ctx.getContext().req;
        const authHeader = req.headers['authorization'] as string | undefined;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new UnauthorizedException('Missing or invalid Authorization header');
        }

        const token = authHeader.substring('Bearer '.length).trim();
        const payload = this.authService.verifyToken(token);

        req.user = {
            id: payload.sub,
            email: payload.email,
            role: payload.role
        };

        return true;
    }
}
