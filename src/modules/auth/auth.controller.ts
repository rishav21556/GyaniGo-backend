import { 
  Controller, 
  Post, 
  Body, 
  Res, 
  Req, 
  HttpCode, 
  HttpStatus,
  UnauthorizedException 
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(
    @Body() signupDto: SignupDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.signup(signupDto);
    // Set both tokens as HTTP-only cookies if they exist
    if (result.access_token && result.refresh_token) {
      await this.authService.setCookie(res, result.access_token, 'access_token', 60 * 60 * 1000); // 1 hour
      await this.authService.setCookie(res, result.refresh_token, 'refresh_token', 7 * 24 * 60 * 60 * 1000); // 7 days
    }
    // Return everything in response body (cookies + response body approach)
    return result;
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(loginDto);
    await this.authService.setCookie(res, result.access_token, 'access_token', 60 * 60 * 1000); // 1 hour
    await this.authService.setCookie(res, result.refresh_token, 'refresh_token', 7 * 24 * 60 * 60 * 1000); // 7 days
    return result;
  }


  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Get access token from cookie first, then fallback to header
    const accessToken = req.cookies?.access_token 
      || (req.headers.authorization?.startsWith('Bearer ') 
        ? req.headers.authorization.split(' ')[1] 
        : null);
    if (accessToken) {
      // Logout on Supabase side
      await this.authService.logout(accessToken);
    }
    // Clear cookies
    await this.authService.clearCookie(res, 'access_token');
    await this.authService.clearCookie(res, 'refresh_token');

    return {
      message: 'Logout successful!',
    };
  }
}
