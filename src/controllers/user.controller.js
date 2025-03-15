// import { asyncHandler } from "../utils/asyncHandler.js";

// const registerUser = asyncHandler( async (req,res) =>{
//      res.status(200).json({
//         message: "Welcome to ViNext"
//     })
// })

// export { registerUser }

import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async (userId)=>{
    try {
        const user = await  User.findById(userId)
        const accessToken=user.generateAccessToken= user.generateAccessToken()
        const refreshToken=user.generateRefreshToken= user.generateRefreshToken()

        user.refreshToken=refreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }
} 

const registerUser = asyncHandler( async (req,res) =>{
     //get user details from frontend
     const {fullName, username, email, password}=req.body;
     console.log("email", email);
     //validation - not empty
    if(
        [fullName, username, email, password].some((field)=>
        field?.trim() === "")
    ){
        throw new ApiError(400, "All fields are required");
    }
     //check if user already exists - username, email
    const existedUser= await User.findOne({
        $or:[{ username },{ email }]
    })
    if(existedUser){
        throw new ApiError(409, "User already exists")
    }
     //check for images, check for avatar
     console.log(req.files);
     const avatarLocalPath = req.files?.avatar[0]?.path;
    //  const coverImageLocalPath = req.files?.coverImage[0]?.path;

     let coverImageLocalPath;
     if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
            coverImageLocalPath = req.files.coverImage[0].path;
     }


     if(!avatarLocalPath){  
         throw new ApiError(400, "Avatar is required")
     }
     //upload them to cloudinary, avatar
     const avatar = await uploadOnCloudinary(avatarLocalPath)
     const coverImage = await uploadOnCloudinary(coverImageLocalPath)

     if(!avatar){
        throw new ApiError(400, "Avatar is required")
    }
     //create user object - create entry in db
     const user = await User.create(
        {
            fullName,
            avatar: avatar.url,
            coverImage: coverImage?.url || "",
            email,
            password,
            username: username.toLowerCase(),
        }
     )
     //remove password and refresh token field from response
     const createdUser = await User.findById(user._id)
     .select(
         "-password -refreshToken"
     )
     //check for user creation
     if(!createdUser){
         throw new ApiError(500, "User registration failed")
     }
     //return response
     return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
     )
})

const loginUser = asyncHandler(async(req,res)=>{
    //req body -> data
    const {email, username, password}=req.body;
    console.log(email)
    //username or email
    if(!email && !username){
        throw new ApiError(400, "Email or username is required")
    }
    //find the user
    const user = await User.findOne({
        $or: [{ email }, { username }]
    })
    if(!user){
        throw new ApiError(404, "User not found")
    }
    //password check
    const isPasswordValid=await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401, "Invalid user credentials")
    }
    //access and refresh token
    const {accessToken, refreshToken}=await generateAccessAndRefreshTokens(user._id)
    const loggedInUser= await User.findById(user._id).
    select("-password -refreshToken")
    //send cookie
    const options = {
        httpOnly: true,
        secure: true
    }
    //return response
    return res
    .status(200)
    .cookie("accessToken",accessToken, options)
    .cookie("refreshToken",refreshToken, options)
    .json(
        new ApiResponse(200,
            {
                user: loggedInUser,
                accessToken,
                refreshToken
            },
            "User logged in successfully"
        )
    )
})

const logoutUser = asyncHandler(async (req,res)=>{
    await User.findByIdAndUpdate(req.user._id,
        {
            $set:{
                refreshToken: undefined
            },
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"))
})

const refreshAccessToken = asyncHandler(async (req,res)=> {
    const incomingRefreshToken =req.cookies.
    refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401, "unauthorized request")
    }
try {
    
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET,
        )
        const user = await User.findById(decodedToken._id)
    
        if(!user){
            throw new ApiError(401, "Invalid refresh Token" )
        }
    
        if(incomingRefreshToken !== user.refreshToken){
            throw new ApiError(401, "Invalid refresh token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newrefreshToken}=await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken, options)
        .cookie("refreshToken",newrefreshToken, options)
        .json(new ApiResponse(200, 
            {accessToken, newrefreshToken}, 
            "Access token refreshed successfully"
        ))
} catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token")
}
})

export { registerUser , loginUser, logoutUser , refreshAccessToken }