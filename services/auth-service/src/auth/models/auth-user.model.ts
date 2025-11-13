import {
    Field,
    ID,
    ObjectType,
    registerEnumType,
    GraphQLISODateTime
} from '@nestjs/graphql';
import { Role } from '@prisma/client';

registerEnumType(Role, { name: 'Role' });

@ObjectType()
export class AuthUserModel {
    @Field(() => ID)
    id!: number;

    @Field()
    email!: string;

    @Field(() => Role)
    role!: Role;

    @Field(() => GraphQLISODateTime)
    createdAt!: Date;

    @Field(() => GraphQLISODateTime)
    updatedAt!: Date;
}
