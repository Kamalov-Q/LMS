import { Field, InputType } from '@nestjs/graphql';
import { Role } from '@prisma/client';

@InputType()
export class RegisterInput {
    @Field()
    email!: string;

    @Field()
    password!: string;

    @Field(() => Role, { nullable: true })
    role?: Role;
}
