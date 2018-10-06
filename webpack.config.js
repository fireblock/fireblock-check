module.exports = {
  output: {
    publicPath: '/dist/'
  },
  devServer: {
    port: 8082,
    inline: true,
    publicPath: '/dist/'
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader"
        }
      }
    ]
  }
};
