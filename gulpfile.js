var p = require('./package.json'),
    gulp = require('gulp'),
    assemblyInfo = require('gulp-dotnet-assembly-info'),
    xmlpoke = require('gulp-xmlpoke'),
    msbuild = require('gulp-msbuild'),
    nuget = require('nuget-runner')({
        apiKey: process.env.NUGET_API_KEY,
        nugetPath: '.nuget/nuget.exe'
    });

gulp.task('default', ['nuget']);

gulp.task('restore', [], function () {
    return nuget
        .restore({
            packages: 'Otp.NET.sln',
            verbosity: 'normal'
        });
});

gulp.task('build', ['restore'], function () {
    return gulp
        .src('Otp.NET.sln')
        .pipe(msbuild({
            toolsVersion: 14.0,
            targets: ['Clean', 'Build'],
            errorOnFail: true,
            configuration: 'Release'
        }));
});

gulp.task('nuspec', ['build'], function () {
    return gulp
        .src('Otp.NET.nuspec')
        .pipe(xmlpoke({
            replacements: [{
                xpath: "//package:version",
                namespaces: { "package": "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd" },
                value: p.version
            }]
        }))
        .pipe(gulp.dest('.'));
});

gulp.task('nuget', ['nuspec'], function () {
    return nuget
        .pack({
            spec: 'Otp.NET.nuspec',
            outputDirectory: 'src/Otp.NET/bin/Release',
            version: p.version
        });
});
