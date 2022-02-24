# frozen_string_literal: true

class Api::AuthenticationController < Devise::SessionsController
  ##//added by KDW
  attr_reader :current_user
  ##before_action :jwt_authenticate_request! ##여기서 걸림 그럼 다른 곳에 클래스를 만들고, 해당 클래스를 상속받으면 어떨까?
  protected

  ## JWT 토큰 검증
  def jwt_authenticate_request!
    ## 토큰 안에 user id 정보가 있는지 확인 / 없을 시 error response 반환
    unless user_id_in_token?
      #render json: {http_token: http_token, auth_toekn: auth_token}
      if refresh_token_valid? #access 무효, refresh 유효
        #render json: {user: http_refresh_token}
        #authenticate_user
        access_issued(http_refresh_token) #refresh를 이용해 access 새롭게 발급
        return
      else
        render json: { message: ['로그인 재요청']}
        # 재로그인 요청
        return
      end
    end

    ## Token 안에 있는 user_id 값을 받아와서 User 모델의 유저 정보 탐색
    @current_user = User.find(auth_token[:user_id])
    #refresh_model(@current_user)
  rescue JWT::VerificationError, JWT::DecodeError
    render json: { errors: ['Not Authenticated'], http_token: http_token}, status: :unauthorized
  end

  private

  ## 토큰 해석 후, Decode 내용 중 User id 정보 확인
  def user_id_in_token?
    http_token && http_refresh_token  && auth_token && auth_token[:user_id].to_i && auth_refresh_token
    #token 검증 경우의 수
    #1. access, refresh모두 정상
    #2. access token만 만료되는 경우
    #3. access, refresh 모두 만료
  end

  def refresh_token_valid?
    http_refresh_token && auth_refresh_token
  end

  def access_issued(token)
    #render json: { errors: ['access만 만료됨']}
    user = User.find_for_database_authentication(refresh: token)
    if user
      payload(user)
      render json: { errors: ['새로운 access 토큰 발급됨']}
    end
    #render json: { :emails => user.email}
    #render json: { refresh: user.refresh}
  end

  ## 헤더에 있는 정보 중, access 내용(토큰) 추출
  def http_token
    http_token ||= if request.headers['access'].present?
      request.headers['access'].split(' ').last
    end
  end

  ######## 헤더에 있는 정보 중, refresh 내용(토큰) 추출
  def http_refresh_token
    http_refresh_token ||= if request.headers['refresh'].present?
      request.headers['refresh'].split(' ').last
    end
  end

  #refresh token은 db에도 저장
  def refresh_model(user)
    user.refresh = http_refresh_token
  end

  ## 토큰 해석 : 토큰 해석은 lib/json_web_token.rb 내의 decode 메소드에서 진행됩니다.
  def auth_token
    auth_token ||= JsonWebToken.decode(http_token)
  end

  def auth_refresh_token
    auth_refresh_token ||= JsonWebToken.decode(http_refresh_token)
  end






  ## JWT 토큰 생성을 위한 Devise 유저 정보 검증
  def authenticate_user
    ## body로 부터 받은 json 형식의 params를 parsing
    json_params = JSON.parse(request.body.read)

    #user = User.find_for_database_authentication(email: "rladlstlf@naver.com")
    #if true
    user = User.find_for_database_authentication(email: json_params["auth"]["email"])
    if user.valid_password?(json_params["auth"]["password"])
      refresh_payload(user)
      render json: payload(user)
    else
      render json: {errors: ['Invalid Username/Password']}, status: :unauthorized
    end
  end

  private

  ## Response으로서 보여줄 json 내용 생성 및 JWT Token 생성
  def payload(user)
    ## 해당 코드 예제에서 토큰 만료기간은 '30일' 로 설정
    @accessToken = JWT.encode({ user_id: user.id, exp: 10.seconds.from_now.to_i }, ENV["DEVISE_JWT_SECRET_KEY"])
    #user.subname = "kiminsil4"
    #user.save
    #@refreshToken = JWT.encode({exp: 120.seconds.from_now.to_i}, ENV["DEVISE_JWT_SECRET_KEY"])
    @tree = { :"JWT token" => @accessToken, :userInfo => {id: user.id, email: user.email, subname: user.subname, refresh: user.refresh }}
    response.headers['access'] = @accessToken
    return @tree
  end


  def refresh_payload(user)
    ## 해당 코드 예제에서 토큰 만료기간은 '30일' 로 설정
    @refreshToken = JWT.encode({exp: 1000.seconds.from_now.to_i}, ENV["DEVISE_JWT_SECRET_KEY"])
    response.headers['refresh'] = @refreshToken
    user.refresh = @refreshToken
    user.save
  end
  ##

  # GET /resource/sign_in
  # def new
  #   super
  # end

  # POST /resource/sign_in
  #def create
  #super
  #end

  # DELETE /resource/sign_out
  # def destroy
  #   super
  # end

  # protected

  # If you have extra params to permit, append them to the sanitizer.

end
