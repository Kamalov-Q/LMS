import {
    Resolver,
    Mutation,
    Args,
    Query
} from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { AuthUserModel } from './models/auth-user.model';
import { AuthPayload } from './models/auth-payload.model';
import { RegisterInput } from './dto/register.input';
import { LoginInput } from './dto/login.input';
import { SendOtpInput } from './dto/send-otp.input';
import { OtpLoginInput } from './dto/otp-login.input';
import { UseGuards } from '@nestjs/common';
import { GqlAuthGuard } from '../common/guards/gql-auth.guard';
import { CurrentUser, CurrentUserData } from '../common/decorators/current-user.decorator';

@Resolver(() => AuthUserModel)
export class AuthResolver {
    constructor(private readonly authService: AuthService) { }

    @Mutation(() => AuthPayload)
    async register(@Args('data') data: RegisterInput): Promise<AuthPayload> {
        const { accessToken, user } = await this.authService.register(data);
        return { accessToken, user };
    }

    @Mutation(() => AuthPayload)
    async login(@Args('data') data: LoginInput): Promise<AuthPayload> {
        const { accessToken, user } = await this.authService.login(data);
        return { accessToken, user };
    }

    @Mutation(() => String, {
        description:
            'Send OTP to email (dev: returns OTP; prod: send via email/SMS)'
    })
    async sendOtp(@Args('data') data: SendOtpInput): Promise<string> {
        const { email, otp } = await this.authService.sendOtp(data);
        // DEV ONLY
        return `OTP for ${email}: ${otp}`;
    }

    @Mutation(() => AuthPayload)
    async otpLogin(@Args('data') data: OtpLoginInput): Promise<AuthPayload> {
        const { accessToken, user } = await this.authService.otpLogin(data);
        return { accessToken, user };
    }

    @UseGuards(GqlAuthGuard)
    @Query(() => AuthUserModel)
    async me(@CurrentUser() user: CurrentUserData): Promise<AuthUserModel> {
        return this.authService.me(user.id);
    }
}
