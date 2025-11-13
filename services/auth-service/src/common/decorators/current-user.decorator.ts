import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

export interface CurrentUserData {
    id: number;
    email: string;
    role: string;
}

export const CurrentUser = createParamDecorator(
    (data: unknown, context: ExecutionContext): CurrentUserData | null => {
        const ctx = GqlExecutionContext.create(context);
        const req = ctx.getContext().req;
        return req.user ?? null;
    }
);
