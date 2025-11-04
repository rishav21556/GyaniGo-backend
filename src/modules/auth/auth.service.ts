import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { supabase } from '../../config/db.config';

@Injectable()
export class AuthService {
  async signup(signupDto: SignupDto) {
    const { email, password } = signupDto;
    
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) {
      throw new BadRequestException(error.message);
    }

    // Check if session exists (won't exist if email confirmation is required)
    if (!data.session) {
      return {
        message: 'Signup successful! Please check your email to confirm your account.',
        user: data.user,
        requiresEmailConfirmation: true,
      };
    }

    // Return access token and refresh token
    return {
      message: 'Signup successful!',
      user: data.user,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
    };
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!data.session) {
      throw new UnauthorizedException('No session created');
    }

    // Return access token and refresh token
    return {
      message: 'Login successful!',
      user: data.user,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
    };
  }

  async logout(accessToken: string) {
    // Sign out using the access token to invalidate it on Supabase's side
    const { error } = await supabase.auth.admin.signOut(accessToken);
    
    if (error) {
      throw new UnauthorizedException('Failed to logout');
    }

    return {
      message: 'Logout successful!',
    };
  }

  async refreshTokens(refreshToken: string) {
    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken,
    });

    if (error || !data.session) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    return {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
      user: data.user,
    };
  }

  async verifyAccessToken(accessToken: string) {
    const { data, error } = await supabase.auth.getUser(accessToken);
    
    if (error || !data.user) {
      return null;
    }

    return data.user;
  }
}
