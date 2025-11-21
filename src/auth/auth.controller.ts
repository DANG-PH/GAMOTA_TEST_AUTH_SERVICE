import { Controller, InternalServerErrorException, ForbiddenException, NotFoundException, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import type { LoginRequest,LoginResponse, RegisterResponse, RegisterRequest, VerifyOtpRequest } from 'proto/auth.pb';
import { AUTH_SERVICE_NAME } from 'proto/auth.pb';

@Controller()
export class AuthController {
  constructor(
    private readonly authService: AuthService,
  ) {}

  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  async register(data: RegisterRequest): Promise<RegisterResponse> {
    return await this.authService.register(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  async login(data: LoginRequest): Promise<LoginResponse> {
    return await this.authService.login(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Refresh')
  async refresh(data: { refreshToken: string }) {
    return await this.authService.refresh(data.refreshToken);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'VerifyOTP')
  async verifyotp( data: VerifyOtpRequest) {
    return await this.authService.verifyOtp(data);
  }
}