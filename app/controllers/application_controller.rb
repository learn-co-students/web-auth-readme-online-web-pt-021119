class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_action :authenticate_user #runs authentication before every controller

private

#authenticate user with foursquare FOURSQUARE_CLIENT_ID
  def authenticate_user
    client_id = ENV['FOURSQUARE_CLIENT_ID']
    redirect_uri = CGI.escape('http://localhost:3000/auth')
    foursquare_url = "https://foursquare.com/oauth2/authenticate?client_id=#{client_id}&response_type=code&redirect_uri=#{redirect_uri}"
    redirect_to foursquare_url unless logged_in?
  end

  #they are logged in if they have a valid token
  def logged_in?
    !!session[:token]
  end

end
