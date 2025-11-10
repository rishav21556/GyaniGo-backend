import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from '../auth.service';

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    // Step 1: Extract access token from Authorization header OR cookie
    let accessToken = this.extractTokenFromHeader(request);
    if (!accessToken) {
      accessToken = request.cookies?.access_token;
    }

    // Step 2: If no access token, try to refresh using refresh token
    if (!accessToken) {
      const refreshToken = request.cookies?.refresh_token;
      if (!refreshToken) {
        throw new UnauthorizedException('No access token or refresh token provided');
      }

      // Try to refresh tokens
      return await this.refreshAndContinue(refreshToken, request, response);
    }

    // Step 3: Verify access token
    const user = await this.authService.verifyAccessToken(accessToken);

    if (user) {
      // Token is valid, attach user to request and continue
      request.user = user;
      return true;
    }

    // Step 4: Access token is invalid/expired, try to refresh
    const refreshToken = request.cookies?.refresh_token;
    if (!refreshToken) {
      throw new UnauthorizedException('Access token expired and no refresh token available');
    }

    return await this.refreshAndContinue(refreshToken, request, response);
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return undefined;
    }
    return authHeader.split(' ')[1];
  }

  private async refreshAndContinue(
    refreshToken: string,
    request: Request,
    response: Response,
  ): Promise<boolean> {
    try {
      // Get new tokens from Supabase
      const result = await this.authService.refreshTokens(refreshToken);

      // Set new tokens in cookies
      response.cookie('access_token', result.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000, // 1 hour
        path: '/',
      });

      response.cookie('refresh_token', result.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/',
      });

      // Attach user to request
      request.user = result.user;

      // Continue with the request
      return true;
    } catch (error) {
      // Clear invalid cookies
      response.clearCookie('access_token');
      response.clearCookie('refresh_token');
      
      throw new UnauthorizedException('Session expired. Please login again.');
    }
  }
}
