import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from './modules/auth/guards/auth.guard';
import { CurrentUser } from './modules/auth/decorators/current-user.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  // Example: Protected route using AuthGuard
  @Get('profile')
  @UseGuards(AuthGuard)
  getProfile(@CurrentUser() user: any) {
    return {
      message: 'This is a protected route!',
      user: user,
    };
  }
}
