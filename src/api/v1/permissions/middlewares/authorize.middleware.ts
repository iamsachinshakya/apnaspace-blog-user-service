import { Request, Response, NextFunction } from "express";
import { ApiError } from "../../common/utils/apiError";
import { ErrorCode } from "../../common/constants/errorCodes";
import { RolePermissions } from "../constants/permission";
import { IAuthUser } from "../../auth/models/auth.dto";

/**
 * RBAC authorization middleware
 * - Verifies authentication
 * - Verifies role
 * - Verifies permission
 */
export const authorize =
    (permission: string) =>
        (req: Request, _res: Response, next: NextFunction) => {
            const user = req.user as IAuthUser | null;

            if (!user) {
                throw new ApiError(
                    "Unauthorized request",
                    401,
                    ErrorCode.UNAUTHORIZED
                );
            }

            const allowedPermissions = RolePermissions[user.role];

            if (!allowedPermissions) {
                throw new ApiError(
                    `Access denied – invalid role: ${user.role}`,
                    403,
                    ErrorCode.INVALID_ROLE
                );
            }

            if (!allowedPermissions.has(permission)) {
                throw new ApiError(
                    "Forbidden – insufficient permissions",
                    403,
                    ErrorCode.PERMISSION_DENIED
                );
            }

            next();
        };
