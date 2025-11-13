import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { GqlAuthGuard } from '../common/guards/gql-auth.guard';

@Module({
    providers: [AuthService, AuthResolver, GqlAuthGuard],
    exports: [AuthService]
})
export class AuthModule { }
