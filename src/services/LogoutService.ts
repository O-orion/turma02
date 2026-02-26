import { jwtConfig } from "../config/jwt.config.js";
import { appDataSource } from "../database/appDataSource.js";
import RefreshToken from "../entities/RefreshToken.js";
import jwt from 'jsonwebtoken'
import { AppError } from "../errors/AppError.js";

export default class LogoutService {

    private repoRefresh = appDataSource.getRepository(RefreshToken);

        async logout(sessionId: string) {
        await this.repoRefresh.update(
            { sessionId },
            { revoked: true }
        );
        }

        async logoutAll(userId: string) {
        await this.repoRefresh.update(
            { pesquisador: { id: userId } },
            { revoked: true }
        );
        }

}
