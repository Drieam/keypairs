# frozen_string_literal: true

Rails.application.routes.draw do
  get :jwks, to: Keypairs::PublicKeysController.action(:index)
end
