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
      res.cookie('access_token', result.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000, // 1 hour (matches Supabase default)
        path: '/',
      });

      res.cookie('refresh_token', result.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/',
      });
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

    // Set both tokens as HTTP-only cookies
    res.cookie('access_token', result.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000, // 1 hour
      path: '/',
    });

    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    // Return everything in response body (cookies + response body approach)
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

    // Clear both cookies
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });

    return {
      message: 'Logout successful!',
    };
  }
}

/*
User signed up: {
  user: {
    id: '749aa565-fdc3-4c6e-bc13-0fd0593f3abe',
    aud: 'authenticated',
    role: 'authenticated',
    email: 'social.rishav.2003@gmail.com',
    phone: '',
    confirmation_sent_at: '2025-11-04T20:36:02.911824268Z',
    app_metadata: { provider: 'email', providers: [Array] },
    user_metadata: {
      email: 'social.rishav.2003@gmail.com',
      email_verified: false,
      phone_verified: false,
      sub: '749aa565-fdc3-4c6e-bc13-0fd0593f3abe'
    },
    identities: [ [Object] ],
    created_at: '2025-11-04T20:36:02.838293Z',
    updated_at: '2025-11-04T20:36:06.003968Z',
    is_anonymous: false
  },
  session: null
}

*/
