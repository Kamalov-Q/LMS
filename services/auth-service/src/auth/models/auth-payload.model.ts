import { Field, ObjectType } from '@nestjs/graphql';
import { AuthUserModel } from './auth-user.model';

@ObjectType()
export class AuthPayload {
    @Field()
    accessToken!: string;

    @Field(() => AuthUserModel)
    user!: AuthUserModel;
}
