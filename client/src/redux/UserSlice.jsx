import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { axiosInstance } from '../Config';

export const fetchUsers = createAsyncThunk('users/fetchUsers', async ({ page, limit }) => {
  const response = await axiosInstance.get(`/user_list?page=${page}&limit=${limit}`);
  return {
    users: response.data.body.data,
    totalPages: response.data.body.totalPages, 
  };
});

export const deleteUser = createAsyncThunk('users/deleteUser', async (_id) => {
  await axiosInstance.delete(`/user_delete/${_id}`);
  return _id; 
});

export const toggleUserStatus = createAsyncThunk(
  'users/toggleUserStatus',
  async ({ id, currentStatus }) => {
    const newStatus = currentStatus === '0' ? '1' : '0';
    const response = await axiosInstance.post('/userstatus', { id, status: newStatus });
    return response.data.success ? { id, newStatus } : { id, newStatus: currentStatus };
  }
);

const userSlice = createSlice({
  name: 'users',
  initialState: {
    users: [],
    error: null,
    loading: false,
    totalPages: 1,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchUsers.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchUsers.fulfilled, (state, action) => {
        state.loading = false;
        state.users = action.payload.users;
        state.totalPages = action.payload.totalPages;
      })
      .addCase(fetchUsers.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      .addCase(deleteUser.fulfilled, (state, action) => {
        state.users = state.users.filter((user) => user._id !== action.payload);
      })
      .addCase(toggleUserStatus.fulfilled, (state, action) => {
        const { id, newStatus } = action.payload;
        const user = state.users.find((user) => user._id === id);
        if (user) {
          user.status = newStatus;
        }
      });
  },
});

export default userSlice.reducer;
