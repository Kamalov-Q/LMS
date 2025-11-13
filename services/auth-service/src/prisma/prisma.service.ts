import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
    async onModuleInit() {
        await this.$connect();

        // Seed default SUPERADMIN if none exists
        const superadminCount = await this.authUser.count({
            where: { role: Role.SUPERADMIN }
        });

        if (superadminCount === 0) {
            const email = process.env.SUPERADMIN_EMAIL || 'superadmin@example.com';
            const password = process.env.SUPERADMIN_PASSWORD || 'superadmin123';
            const passwordHash = await bcrypt.hash(password, 10);

            await this.authUser.create({
                data: {
                    email,
                    passwordHash,
                    role: Role.SUPERADMIN
                }
            });

            console.log(
                `Seeded SUPERADMIN: ${email} / ${password} (change this in production!)`
            );
        }
    }

    async onModuleDestroy() {
        await this.$disconnect();
    }
}
