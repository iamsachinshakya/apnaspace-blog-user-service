import { Request, Response, NextFunction } from "express";
import { ApiError } from "../../common/utils/apiError";
import { ErrorCode } from "../../common/constants/errorCodes";
import { UserRole } from "../../auth/models/auth.entity";
import { IAuthUser } from "../../auth/models/auth.dto";

/**
 * Prevent self action middleware
 * - User CANNOT act on their own resource
 * - Admin can act on anyone
 */
export const authorizeUserAction =
    (message = "Action not allowed on yourself") =>
        (req: Request, _res: Response, next: NextFunction) => {
            const user = req.user as IAuthUser | null;
            const targetUserId = req.params.id;

            if (!user) {
                throw new ApiError(
                    "Unauthorized request",
                    401,
                    ErrorCode.UNAUTHORIZED
                );
            }

            if (!targetUserId) {
                throw new ApiError(
                    "Target user not specified",
                    400,
                    ErrorCode.BAD_REQUEST
                );
            }

            const isSelf = user.id === targetUserId;
            const isAdmin = user.role === UserRole.ADMIN;

            // Admin cannot act on itself
            if (isAdmin && isSelf) {
                throw new ApiError(
                    message,
                    403,
                    ErrorCode.PERMISSION_DENIED
                );
            }

            // Admin can act on others
            if (isAdmin && !isSelf) {
                return next();
            }

            // User can act on itself
            if (!isAdmin && isSelf) {
                return next();
            }

            // User acting on others
            throw new ApiError(
                "You do not have permission to perform this action",
                403,
                ErrorCode.PERMISSION_DENIED
            );
        };
