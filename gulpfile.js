var p = require('./package.json');
var gulp = require('gulp');
var path = require('path');
var del = require('del');
var version = p.version;
var configuration = process.env.BUILD_CONFIGURATION || 'Release';
var {restore, build, test, pack, push} = require('gulp-dotnet-cli');

gulp.task('default', ['nuget', 'test']);

gulp.task('clean', [], ()=>del(['output', 'src/**/bin', 'src/**/obj']))

gulp.task('restore', ['clean'], ()=>{

    return gulp.src('**/*.sln')
               .pipe(restore());

}, {read:false});

gulp.task('build', ['restore'], ()=>{

    return gulp.src('**/*.sln')
               .pipe(build({
                   configuration: configuration,
                   version: version
               }));

}, {read:false});

gulp.task('test', ['build'], ()=>{

    return gulp.src('**/*UnitTests.csproj')
               .pipe(test({
                   configuration: configuration,
                   noBuild: true
                }));
                
}, {read:false});

gulp.task('nuget', ['build'], ()=>{

    return gulp.src('src/Otp.NET/Otp.NET.csproj')
               .pipe(pack({
                   version: p.version,
                   configuration: configuration,
                   output: path.resolve(__dirname, 'output')
               }));

}, {read:false});

gulp.task('push', ['default'], ()=>{

    return gulp.src('output/**/*.nupkg')
               .pipe(push({
                   apiKey: process.env.NUGET_API_KEY
               }));

}, {read:false});