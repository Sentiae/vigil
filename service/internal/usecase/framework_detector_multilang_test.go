package usecase

import "testing"

func TestDetect_ActixWeb(t *testing.T) {
	root := makeProject(t, map[string]string{
		"Cargo.toml": `[package]
name = "svc"
version = "0.1.0"

[dependencies]
actix-web = "4"
tokio = { version = "1", features = ["full"] }
`,
		"src/main.rs": `use actix_web::{web, App, HttpServer};
fn main() {}
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	assertDetected(t, got, "actix-web", 0.75)
}

func TestDetect_SpringBoot(t *testing.T) {
	root := makeProject(t, map[string]string{
		"pom.xml": `<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
      <version>3.1.0</version>
    </dependency>
  </dependencies>
</project>`,
		"src/main/java/App.java": `package app;
import org.springframework.boot.SpringApplication;
@SpringBootApplication
public class App {
  public static void main(String[] args) {}
}
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	assertDetected(t, got, "spring-boot", 0.5)
}

func TestDetect_Rails(t *testing.T) {
	root := makeProject(t, map[string]string{
		"Gemfile": `source 'https://rubygems.org'
gem 'rails', '~> 7.0'
`,
		"config/application.rb": `require 'rails'
module MyApp
  class Application < Rails::Application
  end
end
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	assertDetected(t, got, "rails", 0.5)
}

func TestDetect_Laravel(t *testing.T) {
	root := makeProject(t, map[string]string{
		"composer.json": `{"require":{"laravel/framework":"^11.0"}}`,
		"app/Http/Controllers/UserController.php": `<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class UserController {}
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	assertDetected(t, got, "laravel", 0.5)
}

func TestDetect_AspNetCore(t *testing.T) {
	root := makeProject(t, map[string]string{
		"svc.csproj": `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.App" Version="8.0.0" />
  </ItemGroup>
</Project>`,
		"Program.cs": `using Microsoft.AspNetCore.Builder;
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.Run();
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	assertDetected(t, got, "aspnet-core", 0.5)
}
