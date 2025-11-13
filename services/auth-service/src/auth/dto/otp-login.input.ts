import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class OtpLoginInput {
    @Field()
    email!: string;

    @Field()
    otp!: string;
}
