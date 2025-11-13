import {
    Injectable,
    UnauthorizedException,
    BadRequestException
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterInput } from './dto/register.input';
import { LoginInput } from './dto/login.input';
import { SendOtpInput } from './dto/send-otp.input';
import { OtpLoginInput } from './dto/otp-login.input';
import * as bcrypt from 'bcrypt';
import jwt, { JwtPayload as JwtPayloadLib, SignOptions } from 'jsonwebtoken';
import { Role } from '@prisma/client';
import { z } from 'zod';

const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    role: z.nativeEnum(Role).optional()
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6)
});

const sendOtpSchema = z.object({
    email: z.string().email()
});

const otpLoginSchema = z.object({
    email: z.string().email(),
    otp: z.string().length(6)
});


export interface AuthJwtPayload {
    sub: number;
    email: string;
    role: Role;
    iat?: number;
    exp?: number;
}

@Injectable()
export class AuthService {
    constructor(private readonly prisma: PrismaService) { }

    private get jwtSecret(): string {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
            throw new Error('JWT_SECRET is not set');
        }
        return secret;
    }

    private get jwtExpiresIn(): string {
        return process.env.JWT_EXPIRES_IN || '1d';
    }

    private signToken(user: { id: number; email: string; role: Role }): string {
        const payload: AuthJwtPayload = {
            sub: user.id,
            email: user.email,
            role: user.role
        };

        const options: SignOptions = {
            expiresIn: Number(this.jwtExpiresIn)
        };

        const accessToken = jwt.sign(payload, this.jwtSecret, options);
        return accessToken;
    }

    verifyToken(token: string): AuthJwtPayload {
        try {
            const decoded = jwt.verify(token, this.jwtSecret) as JwtPayloadLib | string;

            if (typeof decoded === 'string' || decoded === null || typeof decoded !== 'object') {
                throw new UnauthorizedException('Invalid token payload');
            }

            const { sub, email, role, iat, exp } = decoded as JwtPayloadLib & {
                sub?: string | number;
                email?: string;
                role?: string;
            };

            if (sub === undefined || email === undefined || role === undefined) {
                throw new UnauthorizedException('Invalid token payload structure');
            }

            const numericSub =
                typeof sub === 'string' ? Number(sub) : sub;

            if (Number.isNaN(numericSub)) {
                throw new UnauthorizedException('Invalid token subject');
            }

            return {
                sub: numericSub,
                email,
                role: role as Role,
                iat,
                exp
            };
        } catch {
            throw new UnauthorizedException('Invalid or expired token');
        }
    }

    async register(input: RegisterInput) {
        const parsed = registerSchema.parse(input);

        const existing = await this.prisma.authUser.findUnique({
            where: { email: parsed.email }
        });

        if (existing) {
            throw new BadRequestException('Email already in use');
        }

        const passwordHash = await bcrypt.hash(parsed.password, 10);

        const user = await this.prisma.authUser.create({
            data: {
                email: parsed.email,
                passwordHash,
                role: parsed.role ?? Role.STUDENT
            }
        });

        const accessToken = this.signToken(user);

        return { accessToken, user };
    }

    async login(input: LoginInput) {
        const parsed = loginSchema.parse(input);

        const user = await this.prisma.authUser.findUnique({
            where: { email: parsed.email }
        });

        if (!user) throw new UnauthorizedException('Invalid credentials');

        const ok = await bcrypt.compare(parsed.password, user.passwordHash);
        if (!ok) throw new UnauthorizedException('Invalid credentials');

        const accessToken = this.signToken(user);

        return { accessToken, user };
    }

    async sendOtp(input: SendOtpInput) {
        const parsed = sendOtpSchema.parse(input);

        const user = await this.prisma.authUser.findUnique({
            where: { email: parsed.email }
        });

        if (!user) {
            throw new BadRequestException('User with this email does not exist');
        }

        // generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await this.prisma.authUser.update({
            where: { id: user.id },
            data: {
                otp,
                otpExpiresAt: expiresAt
            }
        });

        return { email: parsed.email, otp };
    }

    async otpLogin(input: OtpLoginInput) {
        const parsed = otpLoginSchema.parse(input);

        const user = await this.prisma.authUser.findUnique({
            where: { email: parsed.email }
        });

        if (!user || !user.otp || !user.otpExpiresAt) {
            throw new UnauthorizedException('Invalid OTP or email');
        }

        if (user.otp !== parsed.otp) {
            throw new UnauthorizedException('Invalid OTP');
        }

        if (user.otpExpiresAt.getTime() < Date.now()) {
            throw new UnauthorizedException('OTP expired');
        }

        // clear OTP
        const updated = await this.prisma.authUser.update({
            where: { id: user.id },
            data: {
                otp: null,
                otpExpiresAt: null
            }
        });

        const accessToken = this.signToken(updated);

        return { accessToken, user: updated };
    }

    async me(userId: number) {
        const user = await this.prisma.authUser.findUnique({
            where: { id: userId } 
        });
        if (!user) {
            throw new UnauthorizedException('User not found');
        } 
        return user;
    }
}
