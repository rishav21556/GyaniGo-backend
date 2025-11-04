import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Enable cookie parser to read cookies
  app.use(cookieParser());
  
  // Enable CORS with credentials to allow cookies
  app.enableCors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000', // Your frontend URL
    credentials: true,
  });
  
  await app.listen(process.env.PORT ?? 8000);
}
bootstrap();
